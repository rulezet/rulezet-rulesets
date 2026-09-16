rule vb_pcode : info compiler vb
{
    meta:
                description = "VisualBasic compiled to P-Code bytecode"
        
    strings:
        $str_vb_01 = "VB5"
        $str_vb_pcode = { E9 E9 E9 E9 CC CC CC CC CC CC CC CC CC CC CC CC 9E 9E 9E 9E }

    condition:
        ( $str_vb_01 )
        and $str_vb_pcode
}