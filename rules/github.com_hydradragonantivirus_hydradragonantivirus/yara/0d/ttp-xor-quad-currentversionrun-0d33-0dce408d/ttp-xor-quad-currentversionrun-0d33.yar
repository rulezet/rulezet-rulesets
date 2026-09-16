rule TTP_XOR_QUAD_CurrentVersionRun_0d33 {
  strings:
    $key_0d33 = { 5e 5c [2] 7a 52 [2] 51 7e [2] 7f 5c [2] 6b 47 [2] 64 5d [2] 7a 40 [2] 78 41 [2] 63 47 [2] 7f 40 [2] 63 6f }

  condition:
    any of them
}