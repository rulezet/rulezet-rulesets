rule TTP_XOR_QUAD_CurrentVersionRun_3a3f {
  strings:
    $key_3a3f = { 69 50 [2] 4d 5e [2] 66 72 [2] 48 50 [2] 5c 4b [2] 53 51 [2] 4d 4c [2] 4f 4d [2] 54 4b [2] 48 4c [2] 54 63 }

  condition:
    any of them
}