rule crypto_LM_DES: info crypto {
        meta:
                description = "String constant 'KGS!@#$%' used in LM DES"

        strings:
                $lm_des = "KGS!@#$%"

        condition:
                all of them
}