rule TTP_XOR_QUAD_CurrentVersionRun_3d0a {
  strings:
    $key_3d0a = { 6e 65 [2] 4a 6b [2] 61 47 [2] 4f 65 [2] 5b 7e [2] 54 64 [2] 4a 79 [2] 48 78 [2] 53 7e [2] 4f 79 [2] 53 56 }

  condition:
    any of them
}