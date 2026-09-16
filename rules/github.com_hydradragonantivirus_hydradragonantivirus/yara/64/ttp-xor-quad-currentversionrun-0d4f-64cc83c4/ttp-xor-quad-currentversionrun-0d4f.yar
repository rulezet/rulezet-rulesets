rule TTP_XOR_QUAD_CurrentVersionRun_0d4f {
  strings:
    $key_0d4f = { 5e 20 [2] 7a 2e [2] 51 02 [2] 7f 20 [2] 6b 3b [2] 64 21 [2] 7a 3c [2] 78 3d [2] 63 3b [2] 7f 3c [2] 63 13 }

  condition:
    any of them
}