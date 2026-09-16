rule TTP_XOR_QUAD_CurrentVersionRun_b0fe {
  strings:
    $key_b0fe = { e3 91 [2] c7 9f [2] ec b3 [2] c2 91 [2] d6 8a [2] d9 90 [2] c7 8d [2] c5 8c [2] de 8a [2] c2 8d [2] de a2 }

  condition:
    any of them
}