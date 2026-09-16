rule TTP_XOR_QUAD_CurrentVersionRun_576d {
  strings:
    $key_576d = { 04 02 [2] 20 0c [2] 0b 20 [2] 25 02 [2] 31 19 [2] 3e 03 [2] 20 1e [2] 22 1f [2] 39 19 [2] 25 1e [2] 39 31 }

  condition:
    any of them
}