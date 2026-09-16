rule INDICATOR_TOOL_PET_Mulit_VenomAgent {
    meta:
        author = "ditekSHen"
        description = "Detects Venom Proxy Agent"
    strings:
        $s1 = "github.com/Dliv3/Venom/" ascii
        $s2 = "3HpKQVB3nT3qaNQPT-ZU/SKJ55ofz5TEmg5O3ROWA/CUs_-gfa04tGVO633Z4G/OSeEpRRb0Sq_5R6ArIi-" ascii
        $s3 = "venom_agent -" ascii
        $s4 = "bufferssh-userauthtransmitfileunknown portwirep: p->m= != sweepgen" ascii
        $s5 = "golang.org/x/crypto/ssh.(*handshakeTransport).readPacket"
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and 3 of them
}