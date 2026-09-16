rule TTP_XOR_QUAD_CurrentVersionRun_0e3c {
  strings:
    $key_0e3c = { 5d 53 [2] 79 5d [2] 52 71 [2] 7c 53 [2] 68 48 [2] 67 52 [2] 79 4f [2] 7b 4e [2] 60 48 [2] 7c 4f [2] 60 60 }

  condition:
    any of them
}