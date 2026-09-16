rule TTP_XOR_QUAD_CurrentVersionRun_c2cb {
  strings:
    $key_c2cb = { 91 a4 [2] b5 aa [2] 9e 86 [2] b0 a4 [2] a4 bf [2] ab a5 [2] b5 b8 [2] b7 b9 [2] ac bf [2] b0 b8 [2] ac 97 }

  condition:
    any of them
}