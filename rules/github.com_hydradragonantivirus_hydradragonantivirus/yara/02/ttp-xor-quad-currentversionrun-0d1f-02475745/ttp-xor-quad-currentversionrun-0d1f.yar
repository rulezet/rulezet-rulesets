rule TTP_XOR_QUAD_CurrentVersionRun_0d1f {
  strings:
    $key_0d1f = { 5e 70 [2] 7a 7e [2] 51 52 [2] 7f 70 [2] 6b 6b [2] 64 71 [2] 7a 6c [2] 78 6d [2] 63 6b [2] 7f 6c [2] 63 43 }

  condition:
    any of them
}