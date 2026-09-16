rule TTP_XOR_QUAD_CurrentVersionRun_f63c {
  strings:
    $key_f63c = { a5 53 [2] 81 5d [2] aa 71 [2] 84 53 [2] 90 48 [2] 9f 52 [2] 81 4f [2] 83 4e [2] 98 48 [2] 84 4f [2] 98 60 }

  condition:
    any of them
}