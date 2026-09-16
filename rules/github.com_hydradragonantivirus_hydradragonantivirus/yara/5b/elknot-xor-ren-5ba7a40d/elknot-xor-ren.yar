rule elknot_xor_ren: ELF PE DDoS XOR BillGates {
  meta:
    author      = "liuya@360.cn"
    description = "elknot/Billgates variants with XOR like C2 encryption scheme"
    reference   = "http://blog.netlab.360.com/new-elknot-billgates-variant-with-xor-like-c2-configuration-encryption-scheme/"
    date        = "2015-09-12"

  strings:
        
    $decrypt_c2_func_1 = { 08 83 [5] 02 75 07 81 04 24 00 01 00 00 50 e8 [4] e9 }

        
    $decrypt_c2_func_2 = { e8 00 00 00 00 87 [2] 83 eb 05 8d 83 [4] 83 bb [4] 02 75 05 }

  condition:
    1 of ($decrypt_c2_func_*)
}