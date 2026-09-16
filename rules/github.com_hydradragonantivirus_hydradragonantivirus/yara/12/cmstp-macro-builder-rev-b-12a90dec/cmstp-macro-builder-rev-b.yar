rule cmstp_macro_builder_rev_b {
    meta:
        description="CMSTP macro builder based on routines and functions names and runtime invoke"
        author="Palo Alto Networks Unit42"
        reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-new-techniques-uncover-attribute-cobalt-gang-commodity-builders-infrastructure-revealed/"
    strings:
        $func=/Private Function [A-Za-z]{1,5}[0-9]{2,3}\(/
        $sub=/Sub [A-Za-z]{1,5}[0-9]{2,5}\(/
        $call="CallByName"
    condition:
        $call and
        #func > 1 and
        #sub > 1
}