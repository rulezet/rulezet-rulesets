rule TTP_XOR_QUAD_CurrentVersionRun_383c {
  strings:
    $key_383c = { 6b 53 [2] 4f 5d [2] 64 71 [2] 4a 53 [2] 5e 48 [2] 51 52 [2] 4f 4f [2] 4d 4e [2] 56 48 [2] 4a 4f [2] 56 60 }

  condition:
    any of them
}