rule TTP_XOR_QUAD_CurrentVersionRun_0def {
  strings:
    $key_0def = { 5e 80 [2] 7a 8e [2] 51 a2 [2] 7f 80 [2] 6b 9b [2] 64 81 [2] 7a 9c [2] 78 9d [2] 63 9b [2] 7f 9c [2] 63 b3 }

  condition:
    any of them
}