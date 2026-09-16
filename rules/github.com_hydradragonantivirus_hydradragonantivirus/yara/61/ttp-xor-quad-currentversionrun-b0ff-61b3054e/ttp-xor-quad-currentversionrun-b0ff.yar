rule TTP_XOR_QUAD_CurrentVersionRun_b0ff {
  strings:
    $key_b0ff = { e3 90 [2] c7 9e [2] ec b2 [2] c2 90 [2] d6 8b [2] d9 91 [2] c7 8c [2] c5 8d [2] de 8b [2] c2 8c [2] de a3 }

  condition:
    any of them
}