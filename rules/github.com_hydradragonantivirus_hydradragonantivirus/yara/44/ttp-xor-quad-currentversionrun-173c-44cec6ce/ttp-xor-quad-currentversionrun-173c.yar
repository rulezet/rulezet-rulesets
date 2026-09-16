rule TTP_XOR_QUAD_CurrentVersionRun_173c {
  strings:
    $key_173c = { 44 53 [2] 60 5d [2] 4b 71 [2] 65 53 [2] 71 48 [2] 7e 52 [2] 60 4f [2] 62 4e [2] 79 48 [2] 65 4f [2] 79 60 }

  condition:
    any of them
}