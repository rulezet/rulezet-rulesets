rule TTP_XOR_QUAD_CurrentVersionRun_f11e {
  strings:
    $key_f11e = { a2 71 [2] 86 7f [2] ad 53 [2] 83 71 [2] 97 6a [2] 98 70 [2] 86 6d [2] 84 6c [2] 9f 6a [2] 83 6d [2] 9f 42 }

  condition:
    any of them
}