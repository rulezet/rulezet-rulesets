rule TTP_XOR_QUAD_CurrentVersionRun_58ff {
  strings:
    $key_58ff = { 0b 90 [2] 2f 9e [2] 04 b2 [2] 2a 90 [2] 3e 8b [2] 31 91 [2] 2f 8c [2] 2d 8d [2] 36 8b [2] 2a 8c [2] 36 a3 }

  condition:
    any of them
}