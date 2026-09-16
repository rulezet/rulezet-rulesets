rule TTP_XOR_QUAD_CurrentVersionRun_6dfe {
  strings:
    $key_6dfe = { 3e 91 [2] 1a 9f [2] 31 b3 [2] 1f 91 [2] 0b 8a [2] 04 90 [2] 1a 8d [2] 18 8c [2] 03 8a [2] 1f 8d [2] 03 a2 }

  condition:
    any of them
}