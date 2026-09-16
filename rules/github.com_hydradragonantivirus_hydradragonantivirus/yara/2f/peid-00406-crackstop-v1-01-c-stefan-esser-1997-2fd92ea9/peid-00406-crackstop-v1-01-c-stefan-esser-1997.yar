rule PEiD_00406_CrackStop_v1_01__c__Stefan_Esser_1997_ {
  meta:
    description = "[CrackStop v1.01 (c) Stefan Esser 1997]"
    ep_only     = "true"

  strings:
    $a = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC }

  condition:
    $a
}