rule dev_3CX_Gopuram_AppleJeus_Shellcode_Hunt {
  meta:
    author      = "Daniel Mayer (daniel@stairwell.com)"
    description = "A rule for Gopuram shellcode based off of a screenshot of ida in Kaspersky's blog. No promises."
    version     = "1.0"
    date        = "2023-04-03"
    reference1  = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"

  strings:
    $test_hunt = {
      59                          49 89 C8                    48 81 C1 58 06 00 00        BA DA F4 58 F5              49 81 C0 58 D0 06 00        41 B9 39 00 00 00         }

  condition:
    all of them
}