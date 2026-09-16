rule TTP_XOR_QUAD_CurrentVersionRun_6e0f {
  strings:
    $key_6e0f = { 3d 60 [2] 19 6e [2] 32 42 [2] 1c 60 [2] 08 7b [2] 07 61 [2] 19 7c [2] 1b 7d [2] 00 7b [2] 1c 7c [2] 00 53 }

  condition:
    any of them
}