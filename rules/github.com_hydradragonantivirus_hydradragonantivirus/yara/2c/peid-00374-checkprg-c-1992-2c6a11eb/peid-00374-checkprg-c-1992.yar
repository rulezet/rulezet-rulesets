rule PEiD_00374_CHECKPRG__c__1992_ {
  meta:
    description = "[CHECKPRG (c) 1992]"
    ep_only     = "true"

  strings:
    $a = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74 }

  condition:
    $a
}