rule TTP_XOR_QUAD_CurrentVersionRun_db51 {
  strings:
    $key_db51 = { 88 3e [2] ac 30 [2] 87 1c [2] a9 3e [2] bd 25 [2] b2 3f [2] ac 22 [2] ae 23 [2] b5 25 [2] a9 22 [2] b5 0d }

  condition:
    any of them
}