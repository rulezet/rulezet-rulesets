rule TTP_XOR_QUAD_CurrentVersionRun_63fc {
  strings:
    $key_63fc = { 30 93 [2] 14 9d [2] 3f b1 [2] 11 93 [2] 05 88 [2] 0a 92 [2] 14 8f [2] 16 8e [2] 0d 88 [2] 11 8f [2] 0d a0 }

  condition:
    any of them
}