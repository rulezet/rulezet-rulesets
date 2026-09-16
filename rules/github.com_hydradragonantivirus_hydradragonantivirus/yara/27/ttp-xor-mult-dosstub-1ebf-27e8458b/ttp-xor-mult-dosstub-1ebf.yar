rule TTP_XOR_MULT_DOSStub_1ebf {
  strings:
    $key_1ebf = { 4a d7 [2] 3e cf [2] 79 cd [2] 3e dc [2] 70 d0 [2] 7c da [2] 6b d1 [2] 70 9f [2] 4d }

  condition:
    any of them
}