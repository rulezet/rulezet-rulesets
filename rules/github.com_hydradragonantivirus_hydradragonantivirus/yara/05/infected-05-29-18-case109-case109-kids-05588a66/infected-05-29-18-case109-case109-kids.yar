rule _infected_05_29_18_case109_case109_kids {
  meta:
    description = "case109 - file kids.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "3988058b6c0458b0641b39c0239da1217a929d0ce956f014a7f03642f0910be6"

  strings:
    $s1  = "//Shell Recoded From IndoXploit Shell" fullword ascii
    $s2  = "$auth_pass = \"44ee8cb2007d0b0b274293aa224d33d5\"; //default : votrshell" fullword ascii
    $s3  = "$Kidsjamannow= \"7X35e9rIsujPme+b/6Gj8Q32jc1zO4nXGeyAaoyxjZdZHp9RJG6MhSRAU8zk/e2vqhepJQQGh9xmzn2Ts0v0RV3dXV1IXV1deriG4XZ33TAt3Vx" ascii
    $s4  = "//Thanks Buat Yg Udh Support Buat Shell Ini" fullword ascii
    $s5  = "hOEK1cPvkjYo3cNtwWWYySSb/ZTtvj5lPCCmuaI12joafck7Gz63COzHUkCxtE9Jwl7yWGXoXreiaLseHpGkPbWrcsZeUwvPFUukmMhyNMm1EtD6nV5ixNOX3f8H\";" fullword ascii
    $s6  = "//Thanks For Ashura - MA_h4ck0601 - ScarleT7 - Cyber Merah Putih" fullword ascii
    $s7  = "2H25oDwviqLEMgj/cyB2KV4xvSPyUfXvcRZHkYuafb350kuKZf+C0aR7s218WYOmw+woYVZaQ09bY9BN+YenbYjzogJlmTIJ0bChoNVoAWf8SZ0WDcyhjgEI/D66HiBQ" ascii
    $s8  = "T9qLUibmfw8lQWfMRW/MRcGYwZBEdtkFru+3gZwOO1rVeYKWdDdoAzTOLWxZSgL9BpK2AkipBW2qyxr+zXP0CVlys6+BwvpKRf0GdaY+1qCS0+hbwB42RE7C/+Xw/37r" ascii
    $s9  = "eval(str_rot13(gzinflate(str_rot13(base64_decode(($Kidsjamannow))))));" fullword ascii
    $s10 = "###############################################################################" fullword ascii
    $s11 = "s1hCOXTmzCmDOhkj8aaWRld3Kp4cuNEnSRvLj0aSrXy02ktenBJutBKqBcxnrKlU8WCiWc+0/lpZPGQDi+fUAwxfx3Ljqu0XZ8m3zDqoznWTnVfFculsmV3rfkPzp7NI" ascii
    $s12 = "ohteZSk2vDMD1J1Td/dppWuxQihYnh0jmEQgNRU2YIBJ+IMcpfMzA3vSR7ef2j2DPyvXeU4UNNPrba4+hxXRedCT3N1Q+mpz5Cx06KkoKsrscHMAruNEJy4E0TQ1RYXf" ascii
    $s13 = "OryrnH8u+hs3BwP6fWOQLdwB4zk8HBydH5RNvRvO4CQGoNUGVHp1o73nlQe1IyBzj8LGCwnNs+MCMDDBuHV92r8p6kYmBGgPi0h/Dx8o2/fOKD7AfEw/h2dkd7g4D2WI" ascii
    $s14 = "+xflg3eAaKltEPgYY8d2thKXxdRQd7g+yfFotUuFLk8qYBi2xt0WglhdsAsO1gB5aVBaNChtX8Jl7I5eJB+5H+tj7O4Wq0sKbTyq/bq6runLpHRoPMNvw4XanlK4uq+2" ascii
    $s15 = "2lbBp+2i5ZTuq2pFq+w37Fx6+juXIvTceCfFQKYoOIB5OslVZnEqWh23vqhkkFqBNPtQFLov5xo/GyHU9+06Hatd+MIBIn+hAosjBOqlxQzOqd8hdFRu+3OYLA+GNrsF" ascii
    $s16 = "/1GT/1compT2PRFxEsQgNZqcVwCQlLaZABPjGqdDx6TjsjT6nyW+rUygbZz8iMkywqL1S4mmV9+BoeXwxSW2GxI8ikhU7uSrgyBNOnyjCipecoCfImE6y4lpX+HhzRDC" ascii
    $s17 = "lGDffWP9HeZuNAclOKCC+IGtUTmpzBSCioaMDid0Ka4Tyxx1oo6boHz/ZjJY/45KwumfKTxPMXK7n9stN1qNRxFWvL5WGNl5dCCHlhjjN21EK/KiE31TUD9Efoc29PQJ" ascii
    $s18 = "BP0Mc1QFqtdbDRnOAZ414mHE2dddcGlPoCAdhBnAIBT6K2yb02SAg6RpL87JBXy8c9Hjbc8HK38MTlogAnfrBQkf+tmkktsaaz7wqFv4f2U/sacTIPpNQniaO6hPI8/E" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 90KB and
      (8 of them)
    ) or (all of them)
}