rule TTP_XOR_QUAD_CurrentVersionRun_dbe3 {
  strings:
    $key_dbe3 = { 88 8c [2] ac 82 [2] 87 ae [2] a9 8c [2] bd 97 [2] b2 8d [2] ac 90 [2] ae 91 [2] b5 97 [2] a9 90 [2] b5 bf }

  condition:
    any of them
}