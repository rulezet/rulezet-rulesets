rule Arcane_bradlogs_bradmax
{
    meta:
        family = "Arcane"
        fingerprint_id = "bradlogs_bradmax"

    strings:
        $key_0 = "ADMH:" ascii
        $key_1 = "AI Prompt for Business Model Exploration:" ascii
        $key_2 = "AI Prompt for Your Unique Intersection:" ascii
        $key_3 = "AI Prompt to Help You Map Your Passions:" ascii
        $key_4 = "Anime Eyes:" ascii
        $key_5 = "Broken Glasses:" ascii
        $key_6 = "CEP:" ascii
        $key_7 = "CNPJ:" ascii
        $key_8 = "Cidade:" ascii
        $key_9 = "Dados para faturamento:" ascii
        $key_10 = "Destinatar:" ascii
        $key_11 = "Disguise:" ascii
        $key_12 = "EXERCISE 1:" ascii
        $key_13 = "EXERCISE 2:" ascii
        $key_14 = "EXERCISE 3:" ascii
        $key_15 = "EXERCISE 4:" ascii
        $key_16 = "EXERCISE 5:" ascii
        $key_17 = "Eye Patch:" ascii
        $key_18 = "FUNDO:" ascii
        $key_19 = "HITS:" ascii
        $key_20 = "ICU data directory was not discovered:" ascii
        $key_21 = "Instructions:" ascii
        $key_22 = "Inverted Eyes:" ascii
        $key_23 = "Mesaj:" ascii
        $key_24 = "Realistic Eyes:" ascii
        $key_25 = "Rendering thread exception:" ascii
        $key_26 = "Ribbon Bow:" ascii
        $key_27 = "SECTION 1:" ascii
        $key_28 = "SECTION 2:" ascii
        $key_29 = "SECTION 3:" ascii
        $key_30 = "Stuck Out Tongue:" ascii
        $key_31 = "Unhandled Exception:" ascii
        $key_32 = "Vampire Fangs:" ascii

    condition:
        all of ($key_*)
}