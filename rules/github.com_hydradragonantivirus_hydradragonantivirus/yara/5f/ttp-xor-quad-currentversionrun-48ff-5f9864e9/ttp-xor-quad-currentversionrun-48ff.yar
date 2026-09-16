rule TTP_XOR_QUAD_CurrentVersionRun_48ff {
  strings:
    $key_48ff = { 1b 90 [2] 3f 9e [2] 14 b2 [2] 3a 90 [2] 2e 8b [2] 21 91 [2] 3f 8c [2] 3d 8d [2] 26 8b [2] 3a 8c [2] 26 a3 }

  condition:
    any of them
}