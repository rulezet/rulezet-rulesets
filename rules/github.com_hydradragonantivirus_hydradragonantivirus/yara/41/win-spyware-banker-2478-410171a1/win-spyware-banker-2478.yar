rule Win_Spyware_Banker_2478
{
strings:
	$a0 = { 99725268e98d53d3b451761dcf01864a59aeeab091e8228f60fd70fab388273cdb62aa25741f8e5111c1e6e9f5b0791fde1d00d5f7d4cdfa747bedd9f8f927bf7fb71da03b61aa095952 }


condition:
	$a0
}