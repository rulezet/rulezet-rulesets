rule bookworm_payload_match : malware
{
    meta:
         description = "Detect bookworm payload by encrypted header"
         author = "@h3x2b <tracker _AT h3x.eu>"

    strings:
        $bookworm_payload_01 = { b0 78 58 d0 58 20 01 fd 0d 68 68 d0 5d 28 48 e0 58 28 3c 71 68 78 58 d0 }

    condition:
        1 of them
}