rule TTP_XOR_QUAD_CurrentVersionRun_e51e {
  strings:
    $key_e51e = { b6 71 [2] 92 7f [2] b9 53 [2] 97 71 [2] 83 6a [2] 8c 70 [2] 92 6d [2] 90 6c [2] 8b 6a [2] 97 6d [2] 8b 42 }

  condition:
    any of them
}