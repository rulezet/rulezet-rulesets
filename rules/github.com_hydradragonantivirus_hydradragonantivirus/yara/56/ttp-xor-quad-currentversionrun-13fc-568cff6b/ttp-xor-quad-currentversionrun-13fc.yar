rule TTP_XOR_QUAD_CurrentVersionRun_13fc {
  strings:
    $key_13fc = { 40 93 [2] 64 9d [2] 4f b1 [2] 61 93 [2] 75 88 [2] 7a 92 [2] 64 8f [2] 66 8e [2] 7d 88 [2] 61 8f [2] 7d a0 }

  condition:
    any of them
}