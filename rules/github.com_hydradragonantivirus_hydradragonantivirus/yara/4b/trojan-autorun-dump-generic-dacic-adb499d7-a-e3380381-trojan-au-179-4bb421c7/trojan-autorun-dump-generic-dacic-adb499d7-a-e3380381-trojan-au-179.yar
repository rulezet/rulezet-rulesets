import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_ADB499D7_A_E3380381_Trojan_Au_179 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.ADB499D7.A.E3380381.vir, Trojan.Autorun_Dump.Generic.Dacic.ADB499D7.A.E3380381_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46bc7383fb4f03020984aebf3b6124b2a739580ca368f41e2b3759b673521531"
    hash2       = "147546c3f1b39c7425c86052ebb7c00005096c494caf0bf8051ee1522f37399d"

  strings:
    $x1  = "The number of messages to this service that were marked poisoned by the queued transport. http://msdn.microsoft.com/en-US/librar" wide
    $x2  = "The number of messages to this service that were marked poisoned by the queued transport per second. http://msdn.microsoft.com/e" wide
    $s3  = "The number of transactions that flowed to operations at this endpoint. This counter is incremented any time a transaction ID is " wide
    $s4  = "The number of transactions that flowed to operations at this endpoint per second. This counter is incremented any time a transac" wide
    $s5  = "The number of transactions that flowed to operations in this service. This counter is incremented any time a transaction ID is p" wide
    $s6  = "The number of transactions that flowed to operations in this service per second. This counter is incremented any time a transact" wide
    $s7  = "The number of transacted operations with the outcome committed in this service. Work done under such operations is fully committ" wide
    $s8  = "The number of transacted operations with the outcome committed in this service per second. Work done under such operations is fu" wide
    $s9  = "The number of transacted operations with the outcome aborted in this service. Work done under such operations is rolled back. Re" wide
    $s10 = "The number of transacted operations with the outcome aborted in this service per second. Work done under such operations is roll" wide
    $s11 = "The number of transacted operations with an outcome in doubt in this service. Work done with an outcome in doubt is in an indete" wide
    $s12 = "The number of transacted operations with an outcome in doubt in this service per second. Work done with an outcome in doubt is i" wide
    $s13 = "The number of transactions that flowed to this operation. This counter is incremented any time a transaction ID is present in th" wide
    $s14 = "The number of transactions that flowed to this operation per second. This counter is incremented any time a transaction ID is pr" wide
    $s15 = "Count of the number of times login failed due to negotiation failure with target" fullword wide
    $s16 = "The number of calls to this operation that failed validation or authentication. http://msdn.microsoft.com/en-US/library/System.S" wide
    $s17 = "The number of calls to this operation that failed validation or authentication per second. http://msdn.microsoft.com/en-US/libra" wide
    $s18 = "The number of calls to this operation that failed authorization. http://msdn.microsoft.com/en-US/library/System.ServiceModel.Dia" wide
    $s19 = "The number of calls to this operation that failed authorization per second. http://msdn.microsoft.com/en-US/library/System.Servi" wide
    $s20 = "The number of reliable messaging sessions that faulted at this endpoint. http://msdn.microsoft.com/en-US/library/System.ServiceM" wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}