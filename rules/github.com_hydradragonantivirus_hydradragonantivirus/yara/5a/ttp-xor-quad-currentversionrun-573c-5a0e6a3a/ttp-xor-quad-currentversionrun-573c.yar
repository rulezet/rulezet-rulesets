rule TTP_XOR_QUAD_CurrentVersionRun_573c {
  strings:
    $key_573c = { 04 53 [2] 20 5d [2] 0b 71 [2] 25 53 [2] 31 48 [2] 3e 52 [2] 20 4f [2] 22 4e [2] 39 48 [2] 25 4f [2] 39 60 }

  condition:
    any of them
}