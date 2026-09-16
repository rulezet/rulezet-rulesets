rule Stairwell_ChamelDoH_01 {
    meta:
        author = "Daniel Mayer (daniel@stairwell.com)"
        copyright = "(c) 2023 Stairwell, Inc."
        description = "Unique strings from a sample of ChamelDoH"
        last_modified = "2023-06-07"
        version = "0.1"

    strings:
        $ = "001020304050607080910111213141516171819202122232425262728293031"
        $ = "resolve?type=TXT&name="
        $ = "CONNECT_ONLY is required!"
        $ = "[\"ns"
        $ = "touch -r"

    condition:
        4 of them
}