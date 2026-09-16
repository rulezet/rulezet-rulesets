import "pe"
rule EXE_Manager_Version_3_0_1994__c__Solar_Designer {
  strings:
    $a0 = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }

  condition:
    $a0 at pe.entry_point
}