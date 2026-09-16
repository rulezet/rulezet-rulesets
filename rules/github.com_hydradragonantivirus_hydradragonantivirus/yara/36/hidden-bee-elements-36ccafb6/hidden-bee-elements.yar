rule Hidden_Bee_Elements
{
    meta:
        Author      = "InQuest Labs"
        Reference   = "https://blog.malwarebytes.com/threat-analysis/2018/08/reversing-malware-in-a-custom-format-hidden-bee-elements/"
        Description = "This signature detects a custom Windows executable format used in relation to Hidden Bee and Underminer exploit kit."

    strings:
        

        $magic = { 01 03 00 10 }
        $dll   = /(ntdll|kernel32|advapi32|cabinet|msvcrt|ws2_32|phlpape)\.dll/ nocase ascii wide fullword
        
                        $b64_uri = /([\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][Io][Vd][FH][R][Qw][O]i\x38v[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][Io][Vd][FH][R][Qw][Uc][z]ovL[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x30\x32EGUWkm][h][\x30U][Vd][FH][A]\x36Ly[\x2b\x2f\x38-\x39]|[\x2b\x2f-\x39A-Za-z][\x30\x32EGUWkm][h][\x30U][Vd][FH][B][Tz][O]i\x38v[\x2b\x2f-\x39A-Za-z]|[Sa][FH][R][\x30U][Uc][D]ovL[\x2b\x2f-\x39w-z]|[Sa][FH][R][\x30U][Uc][FH][M]\x36Ly[\x2b\x2f\x38-\x39])/

    condition:
        $magic at 0
            and
        (
                        for all i in (1..3) : (@dll[i] < 128)

                or

                        $b64_uri
        )
}