rule TTP_XOR_QUAD_CurrentVersionRun_e51f {
  strings:
    $key_e51f = { b6 70 [2] 92 7e [2] b9 52 [2] 97 70 [2] 83 6b [2] 8c 71 [2] 92 6c [2] 90 6d [2] 8b 6b [2] 97 6c [2] 8b 43 }

  condition:
    any of them
}