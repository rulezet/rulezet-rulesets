rule TTP_XOR_QUAD_CurrentVersionRun_3b3f {
  strings:
    $key_3b3f = { 68 50 [2] 4c 5e [2] 67 72 [2] 49 50 [2] 5d 4b [2] 52 51 [2] 4c 4c [2] 4e 4d [2] 55 4b [2] 49 4c [2] 55 63 }

  condition:
    any of them
}