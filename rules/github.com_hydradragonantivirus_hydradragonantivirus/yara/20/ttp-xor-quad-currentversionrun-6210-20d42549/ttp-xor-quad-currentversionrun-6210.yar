rule TTP_XOR_QUAD_CurrentVersionRun_6210 {
  strings:
    $key_6210 = { 31 7f [2] 15 71 [2] 3e 5d [2] 10 7f [2] 04 64 [2] 0b 7e [2] 15 63 [2] 17 62 [2] 0c 64 [2] 10 63 [2] 0c 4c }

  condition:
    any of them
}