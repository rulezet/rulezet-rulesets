import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_94847_211_1_Trojan_Danger_Gen__446 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.94847_211_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_173_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_254_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01f88d565b126afa1e8bd3e4d829df014b58f8ac24cc1ba8e4e5f999ff4fbca6"
    hash2       = "e9eca68596c96c162ac4ce7b26c12fbdad48d8b746b6146f0ba20256d59f91d8"
    hash3       = "204807b65e154c81eea4dd9950f34274fd79875b5192289c814f10ecebd640aa"

  strings:
    $s1  = "1 Year Subscription: 1K Invoice Line: is defined as one thousand invoice line items processed by the program during a 12 month p" ascii
    $s2  = "1 Year Subscription: 1K Invoice Line: is defined as one thousand invoice line items processed by the program during a 12 month p" ascii
    $s3  = "posted at www.oracle.com/education under the terms specified therein. Learning credits may only be used to acquire productsactur" ascii
    $s4  = "posted at www.oracle.com/education under the terms specified therein. Learning credits may only be used to acquire productsactur" ascii
    $s5  = "um number of named users plus" fullword ascii
    $s6  = "INFORMAL NEGOTIA TION OR IN SMALL CLuser minimum table in the licensing rules section; the minimums table provides for the minim" ascii
    $s7  = "this agreement and Oracle's iLearning Subscription Policies. Oracle's iLearning Subscription Policies may be accessed at for a t" ascii
    $s8  = "this agreement and Oracle's iLearning Subscription Policies. Oracle's iLearning Subscription Policies may be accessed at for a t" ascii
    $s9  = "license to use for your internal business operations anything developed by Oracle and delivered to you under this agreement;ven " ascii
    $s10 = "files and macros to verify the integrity and origin of the file contents. The softw" fullword ascii
    $s11 = "entered electronically from other sources must be licensed separately.downloaded to your computer the next time you" fullword ascii
    $s12 = "license to use for your internal business operations anything developed by Oracle and delivered to you under this agreement;ven " ascii
    $s13 = "by different names such as reseller, distributor, agent, dealer or " fullword ascii
    $s14 = "ing User, Purchasing User, TeleSales User: is defined as an individual authorized by" fullword ascii
    $s15 = "s Update service. alue-added services in marketing" fullword ascii
    $s16 = "prior computer. You may not transfer" fullword ascii
    $s17 = "INFORMAL NEGOTIA TION OR IN SMALL CLuser minimum table in the licensing rules section; the minimums table provides for the minim" ascii
    $s18 = "tiplexing front end. Automated batching of data from computer to computer is permitted. You" fullword ascii
    $s19 = "ng leases and other finance leases," fullword ascii
    $s20 = "hundred and seventy-two thousand four hundred" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "06b18726bdc8f20453f8f1ae22b8d324" and (8 of them)
    ) or (all of them)
}