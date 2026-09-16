rule TTP_XOR_QUAD_CurrentVersionRun_0a3c {
  strings:
    $key_0a3c = { 59 53 [2] 7d 5d [2] 56 71 [2] 78 53 [2] 6c 48 [2] 63 52 [2] 7d 4f [2] 7f 4e [2] 64 48 [2] 78 4f [2] 64 60 }

  condition:
    any of them
}