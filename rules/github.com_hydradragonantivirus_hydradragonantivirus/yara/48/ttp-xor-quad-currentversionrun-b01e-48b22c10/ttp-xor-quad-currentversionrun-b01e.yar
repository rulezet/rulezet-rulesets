rule TTP_XOR_QUAD_CurrentVersionRun_b01e {
  strings:
    $key_b01e = { e3 71 [2] c7 7f [2] ec 53 [2] c2 71 [2] d6 6a [2] d9 70 [2] c7 6d [2] c5 6c [2] de 6a [2] c2 6d [2] de 42 }

  condition:
    any of them
}