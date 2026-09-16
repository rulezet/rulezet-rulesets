rule TTP_XOR_QUAD_CurrentVersionRun_101f {
  strings:
    $key_101f = { 43 70 [2] 67 7e [2] 4c 52 [2] 62 70 [2] 76 6b [2] 79 71 [2] 67 6c [2] 65 6d [2] 7e 6b [2] 62 6c [2] 7e 43 }

  condition:
    any of them
}