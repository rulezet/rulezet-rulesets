rule Hangover_Gimwlog {
    strings:
        $a1 = "file closed---------------------"
        $a2 = "new file------------------"
        $a3 = "md C:\\ApplicationData\\Prefetch\\"
        
    condition:
        all of them

}