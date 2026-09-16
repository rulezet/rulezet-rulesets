rule TTP_XOR_QUAD_CurrentVersionRun_e52e {
  strings:
    $key_e52e = { b6 41 [2] 92 4f [2] b9 63 [2] 97 41 [2] 83 5a [2] 8c 40 [2] 92 5d [2] 90 5c [2] 8b 5a [2] 97 5d [2] 8b 72 }

  condition:
    any of them
}