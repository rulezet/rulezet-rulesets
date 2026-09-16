rule Stairwell_CobaltStrike_Stager_API_Hashing {
  meta:
    author      = "Daniel Mayer (daniel@stairwell.com)"
    description = "Example rule using multiline bytes and comments to annotate instructions. Detects the ror13 API hashing (ror13 is also used by metasploit) routine used by Cobalt Strike"
    hash_x64    = "61b4c29f349f4c5d377934490ca117f87c96b2817e74cea4b2019bea09a9f7fc"
    hash_x86    = "a6f71c9f0ebe8a236e60c6219ca8466c8a2dfbeedfe3fa26bf89b6fb745ee71d"
    version     = "1.0"
    date        = "2023-01-05"

  strings:
    $x64 = {
            48 31 C0           AC                 3C 61              7C 02              2C 20                    41 C1 C9 0D        41 01 C1           E2 ED            }
    $x86 = {
            31 C0           AC              3C 61           7C 02           2C 20                 C1 CF 0D        01 C7           E2 F0         }

  condition:
    any of them
}