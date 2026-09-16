rule TTP_XOR_QUAD_CurrentVersionRun_13ef {
  strings:
    $key_13ef = { 40 80 [2] 64 8e [2] 4f a2 [2] 61 80 [2] 75 9b [2] 7a 81 [2] 64 9c [2] 66 9d [2] 7d 9b [2] 61 9c [2] 7d b3 }

  condition:
    any of them
}